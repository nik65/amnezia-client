param([string]$AdapterPath=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($AdapterPath,[ref]$t,[ref]$e);if($e){throw 'adapter parse failed'}
$f=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Get-GuestConsentProof'},$true));if($f.Count-ne1){throw 'actual function missing'};. ([ScriptBlock]::Create($f[0].Extent.Text))
$ExpectedArtifactSha256='a'*64;$ExpectedConsentPid=-1;$ExpectedConsentStartTime='';$ExpectedConsentSessionId=-1
$Child=@{marker=@{run_id='owned-run';case_id='outer-interactive'};vm=@{Id='00000000-0000-4000-8000-000000000001'}}
function Invoke-Command {param($Session,$ScriptBlock,$ArgumentList);&$ScriptBlock @ArgumentList}
function Test-Path {param($LiteralPath,$PathType);if($LiteralPath-like'*pending-installer.json'-and$script:mode-eq'missing'){return $false};return $true}
function Get-Item {param($LiteralPath,[switch]$Force);[pscustomobject]@{PSIsContainer=$false;Attributes=$(if($script:mode-eq'reparse'){[IO.FileAttributes]::ReparsePoint}else{0});Length=$(if($script:mode-eq'oversize'){65537}else{300})}}
function Get-Content {param($LiteralPath,[switch]$Raw);if($LiteralPath-like'*run-marker.txt'){return @('amnezia-release-lab:owned-run:windows-x64','case_id=outer-interactive','vm_id=00000000-0000-4000-8000-000000000001')};return $script:json}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction);if($Filter-like"Name='consent.exe'"){return [pscustomobject]@{ProcessId=55;SessionId=1;ExecutablePath=(Join-Path $env:SystemRoot 'System32\consent.exe');CreationDate='consent-created'}};if($Filter-eq'ProcessId=44'){return [pscustomobject]@{ProcessId=44;SessionId=1;CommandLine='powershell -File C:\owned\launcher.ps1';CreationDate='launcher-created'}};throw 'unexpected process query'}
function Invoke-CimMethod {param($InputObject,$MethodName,$ErrorAction);if($MethodName-eq'GetOwner'){return [pscustomobject]@{User='SYSTEM'}};return [pscustomobject]@{Sid=$(if($InputObject.ProcessId-eq55){'S-1-5-18'}else{'S-1-5-21-123'})}}
$cases=@('waiting','running','completed','launch-failed','timeout','wrong-run','wrong-case','wrong-artifact','malformed','null','missing','oversize','reparse','message-control','message-quotes','message-unicode','message-missing','message-budget');$results=@()
foreach($case in $cases){
 $script:mode=$case;$r=[ordered]@{state='waiting';run_id='owned-run';case_id='outer-interactive';artifact_sha256=('a'*64);launcher_pid=44;launcher_session_id=1;launcher_path='C:\owned\launcher.ps1';launcher_start_time='launcher-created';installer_pid=$null;artifact_path='token=KEEP_PRIVATE';launch_error=@{stage='Start-Process';message='authorized private Start-Process text';error_type=('X'*300);native_error_code=1223;hresult=-1}}
 switch($case){'running'{$r.state='running'}'completed'{$r.state='completed'}'launch-failed'{$r.state='launch-failed'}'timeout'{$r.state='timeout'}'wrong-run'{$r.run_id='foreign'}'wrong-case'{$r.case_id='outer-clean'}'wrong-artifact'{$r.artifact_sha256='b'*64}}
 if($case-like'message-*'){$r.state='launch-failed'}
 if($case-eq'message-control'){$r.launch_error.message=([string][char]1)*512}
 if($case-eq'message-quotes'){$r.launch_error.message=('"'+[string][char]92)*256}
 if($case-eq'message-unicode'){$r.launch_error.message=([string][char]1046)*512}
 if($case-eq'message-missing'){$r.launch_error.Remove('message')}
 if($case-eq'message-budget'){$r.launch_error.message=([string][char]1)*512;$r.launch_error.error_type=([string][char]2)*128;$r.launch_error.stage=([string][char]3)*128}
 $script:json=$r|ConvertTo-Json -Depth 4 -Compress;if($case-eq'malformed'){$script:json='{broken'};if($case-eq'null'){$script:json='null'}
 $writer=New-Object IO.StringWriter;$prior=[Console]::Error;$failure=$null;$value=$null
 try{[Console]::SetError($writer);try{$value=Get-GuestConsentProof $Child 'inert-session'}catch{$failure=$_}}finally{[Console]::SetError($prior)}
 $consoleText=$writer.ToString();$writer.Dispose();if($consoleText){throw 'diagnostic leaked to remote console'};$text=if($null-ne$failure-and$null-ne$failure.ErrorDetails){$failure.ErrorDetails.Message}else{''};$pass=$case-in@('waiting','running')
 if($pass){if($failure-or$value.expected_consent-ne$true-or$text){throw "validcase $case failed"}}
 else{
  if($null-eq$failure-or$text-notmatch'amnezia-pending-guard '){throw "deniedcase $case lost failure/diagnostic"}
  if($text.Length-gt4200-or$text-match'KEEP_PRIVATE'-or$failure.Exception.Message-match'amnezia-pending-guard'){throw 'diagnostic secret/bounds violation'}
  $d=($text.Substring($text.IndexOf('{')).Trim())|ConvertFrom-Json
  $payload=$text.Substring($text.IndexOf('{'));if($payload.Length-gt4096-or[Text.Encoding]::UTF8.GetByteCount($payload)-gt4096-or$d.observed.launch_error_message.Length-gt512){throw 'private message JSON bounds differ'}
  if($case-eq'launch-failed'-and($d.observed.launch_error_stage-cne'Start-Process'-or$d.observed.launch_error_message-cne'authorized private Start-Process text')){throw 'existing private message/stage lost'}
  if($case-eq'message-budget'-and$d.observed.launch_error_message.Length-ge512){throw 'escaped budget did not trim'}
  if($case-in@('completed','launch-failed','timeout')-and$d.state_ready-ne$false){throw 'terminal state was not rejected'}
  if($case-eq'wrong-run'-and$d.run_matches-ne$false){throw 'run mismatch lost'}
  if($case-eq'wrong-case'-and$d.case_matches-ne$false){throw 'case mismatch lost'}
  if($case-eq'wrong-artifact'-and$d.artifact_matches-ne$false){throw 'artifact mismatch lost'}
 }
 $results+=@([ordered]@{case=$case;passed=$true;accepted=$pass;diagnosticChars=$text.Length})
}
[ordered]@{actualPS=$PSVersionTable.PSVersion.ToString();actualWholeFunction=$true;cases=$results;noGuest=$true;noProduct=$true;noCompiler=$true}|ConvertTo-Json -Depth 6 -Compress
