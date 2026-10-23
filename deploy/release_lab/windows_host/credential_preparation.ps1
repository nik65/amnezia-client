[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$CaseId,
    [Parameter(Mandatory=$true)][string]$VmId,
    [Parameter(Mandatory=$true)][string]$ParentSha256
)
$ErrorActionPreference='Stop'
Import-Module Microsoft.PowerShell.Utility -Force -ErrorAction Stop
if($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$' -or
   $CaseId -notmatch '^(control|thin-clean|thin-upgrade|thin-reinstall|outer-clean|outer-upgrade|outer-reinstall|outer-interactive|publisher-clean)$' -or
   $ParentSha256 -notmatch '^[0-9a-f]{64}$'){throw 'invalid owned guest binding'}
$root="C:\ProgramData\AmneziaReleaseLab\hyperv\runs\$RunId\windows-x64\cases\$CaseId"
$cursor=Get-Item -LiteralPath $root
while($null-ne $cursor){
    if(($cursor.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'reparse ancestor rejected'}
    $cursor=$cursor.Parent
}
$marker=Get-Content -LiteralPath (Join-Path $root '.owned-child.json') -Raw | ConvertFrom-Json
if($marker.backend-cne 'hyperv' -or $marker.profile-cne 'windows-x64' -or
   $marker.run_id-cne $RunId -or $marker.case_id-cne $CaseId -or
   $marker.vm_id-cne $VmId -or $marker.parent_sha256-cne $ParentSha256){throw 'child marker mismatch'}
$vm=Get-VM -Id ([guid]$VmId)
if([string]$vm.State-ne 'Running' -or [string]$vm.Name-cne [string]$marker.vm_name -or
   [int]$vm.Generation-ne 2 -or [int64]$vm.MemoryStartup-ne 8589934592){throw 'child VM configuration mismatch'}
$expectedVmRoot=[IO.Path]::GetFullPath((Join-Path $root 'vm')).TrimEnd('\')+'\'
$actualVmRoot=[IO.Path]::GetFullPath([string]$vm.ConfigurationLocation).TrimEnd('\')+'\'
if(-not $actualVmRoot.StartsWith($expectedVmRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'actual VM configuration escaped owned case root'}
if(@(Get-VMNetworkAdapter -VM $vm).Count-ne 0){throw 'credential preparation requires network-isolated child'}
$disk=@(Get-VMHardDiskDrive -VM $vm)
$expectedDisk=[IO.Path]::GetFullPath((Join-Path $root 'disk\child.vhdx'))
if($disk.Count-ne 1 -or $disk[0].Path-ine $expectedDisk -or [string]$marker.child_vhdx-ine $expectedDisk){throw 'owned child disk mismatch'}
$diskItem=Get-Item -LiteralPath $expectedDisk
if(($diskItem.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'owned child disk is a reparse point'}
$vhd=Get-VHD -Path $disk[0].Path
if($vhd.ParentPath-ine [string]$marker.parent_vhdx){throw 'owned parent disk mismatch'}
$parentRoot='C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64'
$parentMarker=Get-Content -LiteralPath (Join-Path $parentRoot '.owned-vm.json') -Raw | ConvertFrom-Json
if($parentMarker.sealed-ne $true -or $parentMarker.state-cne 'sealed' -or $parentMarker.profile-cne 'windows-x64' -or
   $parentMarker.backend-cne 'hyperv' -or $parentMarker.vm_id-cne [string]$marker.parent_vm_id -or
   $parentMarker.vhdx_sha256-cne $ParentSha256 -or $parentMarker.vhdx-ine $vhd.ParentPath){throw 'sealed parent authority differs'}
$parent=Get-VM -Id ([guid]$marker.parent_vm_id)
if([string]$parent.State-ne 'Off' -or [string]$parent.Id-eq $VmId){throw 'sealed parent must remain Off'}
$request=[Console]::In.ReadToEnd() | ConvertFrom-Json
$action=[string]$request.action
if($action-notin @('authenticate','capture','attention','enter','login','change')){throw 'unsupported credential action'}
$answer=[ordered]@{vm_id=$VmId;run_id=$RunId;case_id=$CaseId;parent_sha256=$ParentSha256;action=$action;installer_started=$false}
function Invoke-Checked($Device,[string]$Method,[hashtable]$Arguments=@{}){
    $result=Invoke-CimMethod -InputObject $Device -MethodName $Method -Arguments $Arguments
    if($result.ReturnValue-ne 0){throw 'owned guest input/capture operation failed'}
    return $result
}
if($action-eq 'authenticate'){
    $secret=[string]$request.credential
    if($secret.Length-lt 12 -or $secret.Length-gt 512){throw 'invalid runtime credential length'}
    $secure=New-Object System.Security.SecureString
    foreach($character in $secret.ToCharArray()){$secure.AppendChar($character)}
    $secure.MakeReadOnly();$secret=$null;$request=$null
    $credential=[PSCredential]::new('.\labadmin',$secure);$session=$null
    try{
        $session=New-PSSession -VMId ([guid]$VmId) -Credential $credential -ErrorAction Stop
        $hostUtc=[DateTime]::UtcNow.ToString('o')
        $answer.account=Invoke-Command -Session $session -ScriptBlock {
            param($utc)
            $u=Get-LocalUser -Name labadmin -ErrorAction Stop
            $before=[DateTime]::UtcNow
            $target=[DateTime]::Parse($utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
            Set-Date -Date ($target.ToLocalTime()) -ErrorAction Stop | Out-Null
            [ordered]@{name=$u.Name;enabled=[bool]$u.Enabled;password_expires=[string]$u.PasswordExpires;
                clock_before_utc=$before.ToString('o');clock_after_utc=[DateTime]::UtcNow.ToString('o');
                host_utc=$utc;clock_offset_before_seconds=($before-$target).TotalSeconds;
                clock_offset_after_seconds=([DateTime]::UtcNow-$target).TotalSeconds}
        } -ArgumentList $hostUtc
        if(-not $answer.account.enabled){throw 'guest account disabled'}
        $answer.authenticated=$true
    }catch{
        $answer.authenticated=$false
        $answer.invalid_credential=($_.Exception -is [System.Management.Automation.Remoting.PSDirectException] -and
            [string]$_.Exception.Message -match '(?i)credential.*invalid|\u043d\u0435\u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c.*\u0443\u0447\u0435\u0442\u043d')
        $answer.error_id=[string]$_.FullyQualifiedErrorId
    }finally{if($null-ne $session){Remove-PSSession $session}}
}else{
    $sys=Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter "Name='$VmId'"
    $keyboards=@(Get-CimAssociatedInstance -InputObject $sys -ResultClassName Msvm_Keyboard)
    if($keyboards.Count-ne 1){throw 'ambiguous VM keyboard'}
    $keyboard=$keyboards[0]
    if($action-eq 'capture'){
        $settings=@(Get-CimAssociatedInstance -InputObject $sys -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData)
        if($settings.Count-ne 1){throw 'ambiguous current VM setting'}
        $service=Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_VirtualSystemManagementService
        $result=Invoke-Checked $service 'GetVirtualSystemThumbnailImage' @{TargetSystem=$settings[0];WidthPixels=[uint16]1024;HeightPixels=[uint16]768}
        if($result.ImageData.Count-notin @(1572864,1572868)){throw 'unexpected thumbnail size'}
        $answer.rgb565=[Convert]::ToBase64String([byte[]]$result.ImageData)
    }elseif($action-eq 'attention'){
        Invoke-Checked $keyboard 'TypeCtrlAltDel' | Out-Null
    }elseif($action-eq 'enter'){
        Invoke-Checked $keyboard 'TypeKey' @{KeyCode=[uint32]13} | Out-Null
    }else{
        $controllers=@(Get-CimAssociatedInstance -InputObject $sys -ResultClassName Msvm_SyntheticDisplayController)
        $heads=@($controllers | ForEach-Object {Get-CimAssociatedInstance -InputObject $_ -ResultClassName Msvm_VideoHead})
        $heads=@($heads | Where-Object {$_.CurrentHorizontalResolution-gt 0 -and $_.CurrentVerticalResolution-gt 0})
        if($heads.Count-ne 1 -or $heads[0].CurrentHorizontalResolution-ne 1024 -or $heads[0].CurrentVerticalResolution-ne 768){throw 'credential UI requires reviewed 1024x768 display'}
        $mice=@(Get-CimAssociatedInstance -InputObject $sys -ResultClassName Msvm_SyntheticMouse)
        if($mice.Count-ne 1){throw 'ambiguous VM mouse'}
        function Fill-Field([int]$X,[int]$Y,[string]$Text,[switch]$Focused){
            if($X-lt 350 -or $X-gt 650 -or $Y-lt 350 -or $Y-gt 540 -or $Text.Length-lt 12 -or $Text.Length-gt 512 -or $Text-match '[^\x20-\x7e]'){throw 'credential field/input outside reviewed contract'}
            if(-not $Focused){
                Invoke-Checked $mice[0] 'SetAbsolutePosition' @{HorizontalPosition=$X;VerticalPosition=$Y} | Out-Null
                Start-Sleep -Milliseconds 250
                Invoke-Checked $mice[0] 'ClickButton' @{ButtonIndex=[uint32]1} | Out-Null
                Start-Sleep -Milliseconds 250
            }
            Invoke-Checked $keyboard 'PressKey' @{KeyCode=[uint32]17} | Out-Null
            try{Invoke-Checked $keyboard 'TypeKey' @{KeyCode=[uint32]65} | Out-Null}
            finally{Invoke-Checked $keyboard 'ReleaseKey' @{KeyCode=[uint32]17} | Out-Null}
            Invoke-Checked $keyboard 'TypeText' @{AsciiText=$Text} | Out-Null
            Start-Sleep -Milliseconds 500
        }
        if($action-eq 'login'){
            Fill-Field ([int]$request.x) ([int]$request.y) ([string]$request.credential)
        }else{
            Fill-Field ([int]$request.x) ([int]$request.old_y) ([string]$request.old)
            Invoke-Checked $keyboard 'TypeKey' @{KeyCode=[uint32]9} | Out-Null
            Start-Sleep -Milliseconds 500
            Fill-Field ([int]$request.x) ([int]$request.new_y) ([string]$request.new) -Focused
            Invoke-Checked $keyboard 'TypeKey' @{KeyCode=[uint32]9} | Out-Null
            Start-Sleep -Milliseconds 500
            Fill-Field ([int]$request.x) ([int]$request.confirm_y) ([string]$request.new) -Focused
        }
        $request=$null
        Invoke-Checked $keyboard 'TypeKey' @{KeyCode=[uint32]13} | Out-Null
    }
}
$answer | ConvertTo-Json -Depth 8 -Compress
