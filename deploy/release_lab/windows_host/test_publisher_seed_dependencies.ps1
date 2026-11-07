# Pure mocked guest-block regression; only the sibling adapter source is read.
$Adapter=Join-Path $PSScriptRoot 'hyperv_adapter.ps1'
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Adapter,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'adapter AST failed'}
$blocks=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.ScriptBlockAst]-and$null-ne$n.ParamBlock-and$n.ParamBlock.Parameters.Count-eq5-and$n.Extent.Text.Contains('$requiredNames=@(')},$true))
if($blocks.Count-ne1){throw 'unique actual guest dependency block required'}
$block=[scriptblock]::Create($blocks[0].Extent.Text.TrimStart('{').TrimEnd('}'))
$script:run='ordinary-lab-run_42';$script:case='publisher-clean';$script:vm='11111111-1111-1111-1111-111111111111';$script:nonce='d'*48
$script:caseRoot="C:\ProgramData\AmneziaLab\runs\$script:run\windows-x64\$script:case";$script:seedRoot=Join-Path $script:caseRoot 'publisher';$script:installed='C:\Program Files\AmneziaVPN'
$script:required=@('Qt6Core.dll','icuuc.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll','msvcp140_codecvt_ids.dll','vcruntime140.dll','vcruntime140_1.dll')
function Add-Fake([string]$Path,[bool]$Directory,[string]$Content='',[string]$Hash=('a'*64)){
 $script:files[$Path]=[pscustomobject]@{FullName=$Path;PSIsContainer=$Directory;Attributes=if($Directory){[IO.FileAttributes]::Directory}else{[IO.FileAttributes]::Normal};Length=if($Directory){0}else{1234};Content=$Content;Hash=$Hash}
}
function Test-Path{param($LiteralPath,$PathType)
 if(-not$script:files.ContainsKey([string]$LiteralPath)){return $false}
 if($PathType-eq'Container'){return $script:files[[string]$LiteralPath].PSIsContainer}
 if($PathType-eq'Leaf'){return -not$script:files[[string]$LiteralPath].PSIsContainer}
 return $true
}
function Get-Item{param($LiteralPath,[switch]$Force,$ErrorAction)
 if(-not$script:files.ContainsKey([string]$LiteralPath)){throw [IO.FileNotFoundException]::new('inert guest required file absent')}
 return $script:files[[string]$LiteralPath]
}
function Get-Content{param($LiteralPath,[switch]$Raw,$ErrorAction)
 $f=Get-Item $LiteralPath
 if($Raw){return $f.Content}
 return $f.Content.Split("`n")
}
function Get-FileHash{param($LiteralPath,$Algorithm,$ErrorAction)
 $f=Get-Item $LiteralPath
 $script:hashCalls[[string]$LiteralPath]++
 $hash=$f.Hash
 if($script:mode-eq'source-changed'-and$LiteralPath-eq(Join-Path $script:installed 'Qt6Core.dll')-and$script:hashCalls[[string]$LiteralPath]-gt1){$hash='b'*64}
 [pscustomobject]@{Hash=$hash}
}
function New-Item{param($ItemType,$Path,$Value,$ErrorAction)
 if($script:files.ContainsKey([string]$Path)){throw 'inert unexpected overwrite'}
 Add-Fake $Path ($ItemType-eq'Directory') ([string]$Value)
 return $script:files[[string]$Path]
}
function Copy-Item{param($LiteralPath,$Destination,$ToSession,$ErrorAction)
 if($null-ne$ToSession){throw 'dependency copy must not use host ToSession'}
 if(-not([string]$LiteralPath).StartsWith($script:installed+'\')-or-not([string]$Destination).StartsWith($script:seedRoot+'\')){throw 'guest dependency copy origin/destination wrong'}
 $source=Get-Item $LiteralPath;$script:copies++
 Add-Fake $Destination $false '' $source.Hash
 if($script:mode-eq'copy-corrupted'){$script:files[[string]$Destination].Hash='c'*64}
}
function Reset-Fixture([string]$Mode){
 $script:mode=$Mode;$script:files=@{};$script:hashCalls=@{};$script:copies=0
 foreach($d in @('C:\','C:\ProgramData','C:\ProgramData\AmneziaLab','C:\ProgramData\AmneziaLab\runs',"C:\ProgramData\AmneziaLab\runs\$script:run",("C:\ProgramData\AmneziaLab\runs\$script:run\windows-x64"),$script:caseRoot,'C:\Program Files',$script:installed)){Add-Fake $d $true}
 Add-Fake (Join-Path $script:caseRoot 'run-marker.txt') $false ("amnezia-release-lab:$script:run`:windows-x64`nbackend=hyperv`ncase_id=$script:case`nvm_id=$script:vm")
 $script:files[(Join-Path $script:caseRoot 'run-marker.txt')].Length=200
 foreach($name in $script:required){Add-Fake (Join-Path $script:installed $name) $false}
 if($Mode-eq'missing'){$script:files.Remove((Join-Path $script:installed 'Qt6Core.dll'))}
 if($Mode-eq'foreign-marker'){$script:files[(Join-Path $script:caseRoot 'run-marker.txt')].Content='foreign'}
 if($Mode-eq'reparse'){$script:files[$script:installed].Attributes=[IO.FileAttributes]::ReparsePoint}
 if($Mode-in@('nonce-mismatch','destination-collision')){
  Add-Fake $script:seedRoot $true
  Add-Fake (Join-Path $script:seedRoot 'attempt-nonce.txt') $false $(if($Mode-eq'nonce-mismatch'){'foreign'}else{$script:nonce})
  $script:files[(Join-Path $script:seedRoot 'attempt-nonce.txt')].Length=48
 }
 if($Mode-eq'destination-collision'){Add-Fake (Join-Path $script:seedRoot 'Qt6Core.dll') $false '' ('f'*64)}
}
$checks=0
foreach($mode in @('valid','missing','foreign-marker','foreign-path','reparse','nonce-mismatch','destination-collision','source-changed','copy-corrupted')){
 Reset-Fixture $mode
 $path=if($mode-eq'foreign-path'){'C:\foreign'}else{$script:seedRoot}
 $failed=$false;$result=$null
 try{$result=@(&$block $path $script:nonce $script:run $script:case $script:vm)}catch{$failed=$true;$reason=$_.Exception.Message}
 if($mode-eq'valid'){
  if($failed){throw "positive guest block failed: $reason"}
  if($result.Count-ne1-or$result[0]-isnot[Collections.IDictionary]-or$result[0].files.Count-ne9-or$script:copies-ne9-or$result[0].host_installed_files_read-ne$false-or$result[0].source_root-ne$script:installed){throw 'guest copy lacks exact scalar provenance/readback'}
 }elseif(-not$failed){throw "invalid mode $mode accepted"}
 if($mode-in@('missing','foreign-marker','foreign-path','reparse','nonce-mismatch','destination-collision')-and$script:copies-ne0){throw 'invalid source/identity copied dependencies'}
 $checks++
}
[ordered]@{status='PASS';actualGuestBlockCases=$checks;fileSystemCommandsMocked=$true;hostInstalledFilesRead=$false;guestUsed=$false;helperStarted=$false}|ConvertTo-Json -Compress
