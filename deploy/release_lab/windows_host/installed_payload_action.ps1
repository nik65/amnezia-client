# Fixed read-only action. Called only after the adapter obtains fresh Read-Child.
function Read-OwnedInstalledPayload {
 param($Child,[string]$RunId,[string]$CaseId,[string]$ArtifactSha,[long]$ArtifactSize,[string]$Role,[string]$Version,[string]$Nonce)
 if([string]$Child.vm.State-ne 'Running' -or [string]$Child.marker.run_id-cne $RunId -or [string]$Child.marker.case_id-cne $CaseId -or [string]$Child.marker.vm_id-cne [string]$Child.vm.Id){throw 'installed payload requires actual owned running child'}
 if($ArtifactSha-notmatch '^[0-9a-f]{64}$' -or $ArtifactSize-le 0 -or $Role-notin @('baseline','candidate') -or $Version-cne '5.0.3.11' -or $Nonce-notmatch '^[0-9a-f]{48}$'){throw 'installed payload expected identity invalid'}
 $session=New-Session $Child
 try{
  $result=Invoke-Command -Session $session -ScriptBlock {
   param($id,$case,$vm,$sha,$size,$role,$version,$nonce)
   function Assert-Regular([string]$path){
    for($current=$path;$current;$current=Split-Path -Parent $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if(($item.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'installed payload reparse path rejected'};if($current-eq [IO.Path]::GetPathRoot($current)){break}}
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if($file.PSIsContainer){throw 'installed payload must be regular file'};return $file
   }
   $root="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"
   $marker=Join-Path $root 'run-marker.txt';[void](Assert-Regular $marker)
   $lines=@(Get-Content -LiteralPath $marker)
   $expected=@("amnezia-release-lab:${id}:windows-x64",'backend=hyperv',"case_id=$case","vm_id=$vm")
   if($lines.Count-ne 4 -or @(Compare-Object $expected $lines).Count-ne 0){throw 'installed payload guest marker differs'}
   $artifact=Join-Path $root 'current.exe';$info=Assert-Regular $artifact
   if($info.Length-ne $size -or (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()-cne $sha){throw 'installed payload current artifact differs'}
   $paths=[ordered]@{app='C:\Program Files\AmneziaVPN\AmneziaVPN.exe';service='C:\Program Files\AmneziaVPN\AmneziaVPN-service.exe'}
   $files=[ordered]@{}
   foreach($name in $paths.Keys){$path=$paths[$name];$file=Assert-Regular $path;$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();$ver=$file.VersionInfo
    if($ver.FileVersion-cne $version -or $ver.ProductVersion-cne $version){throw 'installed payload version differs'}
    $files[$name]=[ordered]@{path=$path;sha256=$hash;size=[long]$file.Length;file_version=[string]$ver.FileVersion;product_version=[string]$ver.ProductVersion}
   }
   $service=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction Stop
   if($null-eq $service -or $service.State-cne 'Running' -or $service.ProcessId-le 0 -or $service.PathName.Trim('"')-cne $paths.service){throw 'installed service fixed image differs'}
   $process=Get-Process -Id $service.ProcessId -ErrorAction Stop
   if($process.Path-cne $paths.service){throw 'installed service process image differs'}
   $start=$process.StartTime.ToUniversalTime().Ticks
   foreach($name in $paths.Keys){$file=Assert-Regular $paths[$name];if($file.Length-ne $files[$name].size -or (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash.ToLowerInvariant()-cne $files[$name].sha256){throw 'installed payload changed during observation'}}
   $again=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction Stop;$process.Refresh()
   if($again.ProcessId-ne $process.Id -or $again.State-cne 'Running' -or $process.HasExited -or $process.StartTime.ToUniversalTime().Ticks-ne $start){throw 'installed service identity changed during observation'}
   [ordered]@{action='installed-payload';run_id=$id;case_id=$case;vm_id=$vm;artifact_sha256=$sha;artifact_size=[long]$size;artifact_role=$role;version=$version;nonce=$nonce;transport='hyperv-powershell-direct';origin='guest';injected=$false;read_only=$true;files=$files;service=[ordered]@{name='AmneziaVPN-service';state='Running';image_path=$paths.service;pid=[int]$process.Id;start_ticks=[long]$start}}
  } -ArgumentList $RunId,$CaseId,([string]$Child.vm.Id),$ArtifactSha,$ArtifactSize,$Role,$Version,$Nonce
  $result|Add-Member -NotePropertyName parent_sha256 -NotePropertyValue $Child.parent.sha256
  return $result
 }finally{if($null-ne $session){Remove-PSSession $session}}
}
