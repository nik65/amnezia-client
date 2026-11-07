param([Parameter(Mandatory=$true)][string]$Adapter,[Parameter(Mandatory=$true)][string]$Scratch)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Adapter,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'source parse error'}
foreach($name in @('Full','Assert-Contained','Get-OwnedConsentConsole')){
 $function=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
 if($function.Count-ne1){throw 'unique actual function required'}
 Invoke-Expression $function[0].Extent.Text
}
function Fail($message){throw $message}
function Sha($path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
$script:vm='11111111-1111-1111-1111-111111111111'
$AttemptNonce='d'*32;$ExpectedArtifactSha256='a'*64
$child=[pscustomobject]@{vm=[pscustomobject]@{Id=$script:vm};root=$Scratch}
$script:before=[pscustomobject]@{run_id='fixture';case_id='outer-interactive';vm_id=$script:vm;process_id=42;creation_time='consent-start';session_id=1;owner_sid='S-1-5-18';consent_path='C:\Windows\System32\consent.exe';launcher_pid=41;launcher_start_time='launcher-start';launcher_session_id=1;launcher_sid='S-1-5-21-fixture'}
$script:mode='plain';$script:providerCalls=0;$script:guestCalls=0;$script:classCalls=0
$script:payload=New-Object byte[] (1280*720*2)
$script:payload[0]=31;$script:payload[1]=248;$script:payload[$script:payload.Length-1]=127
function Get-CimInstance{param($Namespace,$ClassName,$Filter,$ErrorAction)
 if($Namespace-ne'root\virtualization\v2'){throw 'unreviewed CIM namespace'}
 if($ClassName-eq'Msvm_ComputerSystem'){
  if($Filter-ne"Name='$script:vm'"){throw 'foreign VM query'}
  return [pscustomobject]@{Name=$script:vm}
 }
 if($ClassName-eq'Msvm_VirtualSystemManagementService'){return [pscustomobject]@{Name='service'}}
 throw 'unexpected real CIM request'
}
function Get-CimAssociatedInstance{param($InputObject,$Association,$ResultClassName,$ErrorAction)
 if($InputObject.Name-ne$script:vm-or$Association-ne'Msvm_SettingsDefineState'-or$ResultClassName-ne'Msvm_VirtualSystemSettingData'){throw 'foreign settings query'}
 $id=$script:vm;if($script:mode-eq'foreign-setting'){$id='foreign'}
 $type='Microsoft:Hyper-V:System:Realized';if($script:mode-eq'snapshot-setting'){$type='Microsoft:Hyper-V:Snapshot:Realized'}
 [pscustomobject]@{VirtualSystemType=$type;VirtualSystemIdentifier=$id}
}
function Get-CimClass{param($Namespace,$ClassName,$ErrorAction)
 $script:classCalls++
 if($Namespace-ne'root\virtualization\v2'-or$ClassName-ne'Msvm_VirtualSystemManagementService'){throw 'unreviewed CIM metadata query'}
 $qualifier=$true
 if($script:mode-eq'qualifier-false'){$qualifier=$false}
 if($script:mode-eq'qualifier-string'){$qualifier='True'}
 [pscustomobject]@{CimClassMethods=@{GetVirtualSystemThumbnailImage=[pscustomobject]@{Parameters=@{ImageData=[pscustomobject]@{Qualifiers=@{OctetString=[pscustomobject]@{Value=$qualifier}}}}}}}
}
function Invoke-CimMethod{param($InputObject,$MethodName,$Arguments,$ErrorAction)
 $script:providerCalls++
 if($MethodName-ne'GetVirtualSystemThumbnailImage'-or$Arguments.TargetSystem.VirtualSystemIdentifier-ne$script:vm-or$Arguments.WidthPixels-ne1280-or$Arguments.HeightPixels-ne720){throw 'target/dimensions changed'}
 $result=0;if($script:mode-eq'provider-denied'){$result=32769};if($script:mode-eq'provider-async'){$result=4096}
 [byte[]]$raw=$script:payload
 if($script:mode-eq'framed'){$raw=[byte[]](@(0,28,32,4)+$script:payload)}
 if($script:mode-eq'bad-header'){$raw=[byte[]](@(0,28,32,0)+$script:payload)}
 if($script:mode-eq'bad-endian'){$raw=[byte[]](@(4,32,28,0)+$script:payload)}
 if($script:mode-eq'extra'){$raw=[byte[]]($script:payload+@(0))}
 if($script:mode-eq'short'){$raw=[byte[]]$script:payload[0..($script:payload.Length-2)]}
 [pscustomobject]@{ReturnValue=$result;ImageData=$raw}
}
function Get-GuestConsentProof{param($Child,$Session)
 $script:guestCalls++;$proof=$script:before.PSObject.Copy()
 if($script:mode-eq'consent-replaced'){$proof.process_id=43}
 return $proof
}
$checks=0
foreach($mode in @('plain','framed')){
 $script:mode=$mode;$script:providerCalls=0;$script:guestCalls=0;$script:classCalls=0
 $items=@(Get-OwnedConsentConsole $child 'inert-session' $script:before)
 if($items.Count-ne1-or$items[0]-isnot[Collections.IDictionary]){throw 'CAPTURE_RETURN_MUST_BE_EXACTLY_ONE_OBJECT'}
 $capture=$items[0]
 $json=[ordered]@{console_capture=$capture}|ConvertTo-Json -Depth 30 -Compress
 $parsed=$json|ConvertFrom-Json
 if($parsed.console_capture-is[Array]-or$parsed.console_capture.method-ne'Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage'){throw 'wire JSON capture is not one object'}
 if($capture.vm_id-ne$script:vm-or$capture.artifact_sha256-ne$ExpectedArtifactSha256-or$capture.size-ne$script:payload.Length-or$capture.sha256-ne(Sha $capture.host_path)-or$script:providerCalls-ne1-or$script:guestCalls-ne1-or$script:classCalls-ne1){throw 'capture binding/call count mismatch'}
 $actual=[IO.File]::ReadAllBytes($capture.host_path)
 if($actual.Length-ne$script:payload.Length-or$actual[0]-ne31-or$actual[1]-ne248-or$actual[$actual.Length-1]-ne127){throw 'normalized actual pixels changed'}
 $original=Join-Path (Split-Path $capture.host_path -Parent) $capture.provider_raw_file_name
 if((Sha $original)-ne$capture.provider_raw_sha256-or(Get-Item -LiteralPath $original).Length-ne$capture.provider_raw_size){throw 'original provider bytes missing/unbound'}
 $offset=if($mode-eq'plain'){0}else{4}
 if($capture.provider_payload_offset-ne$offset-or$capture.provider_raw_size-ne($script:payload.Length+$offset)-or$capture.provider_octet_string_qualifier-ne$true){throw 'provider frame metadata differs'}
 $checks++
}
$filesBefore=@(Get-ChildItem -LiteralPath (Join-Path $Scratch 'evidence') -File).Count
foreach($mode in @('provider-denied','provider-async','bad-header','bad-endian','extra','short','qualifier-false','qualifier-string','foreign-setting','snapshot-setting','consent-replaced')){
 $script:mode=$mode;$failed=$false
 try{Get-OwnedConsentConsole $child 'inert-session' $script:before|Out-Null}catch{$failed=$true}
 if(-not$failed){throw "invalid mode $mode accepted"}
 if(@(Get-ChildItem -LiteralPath (Join-Path $Scratch 'evidence') -File).Count-ne$filesBefore){throw "failed mode $mode published evidence"}
 $checks++
}
$script:mode='plain';$AttemptNonce='bad';$failed=$false
try{Get-OwnedConsentConsole $child 'inert-session' $script:before|Out-Null}catch{$failed=$true}
if(-not$failed){throw 'invalid attempt accepted'}
$checks++
[ordered]@{status='PASS';fullFunctionCases=$checks;captureReturnObjects=1;wireCaptureType='object';allCimCallsMocked=$true;guestStarted=$false}|ConvertTo-Json -Compress
