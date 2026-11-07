$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'limited_interactive_controller.ps1'))
$start=$text.IndexOf(' $access=$proof.fixture_access');$end=$text.IndexOf(' $gui=Get-Process',$start)
if($start-lt0-or$end-lt$start){throw 'actual proof validator source absent'}
$validate=[scriptblock]::Create($text.Substring($start,$end-$start))
$root='C:\ProgramData\AmneziaLab\runs\unit-run\windows-x64\outer-clean\netstack-fixture';$inputDir=Join-Path $root 'limited-input';$output=Join-Path $root 'limited-output'
$required=@($root,$inputDir,(Join-Path $inputDir 'limited_interactive_runner.ps1'),(Join-Path $inputDir 'BoundedOperatorCapture.cs'),(Join-Path $inputDir 'plan.json'),(Join-Path (Split-Path -Parent $root) 'run-marker.txt'))+@('fixture.exe','product_observer.ps1','limited_interactive_controller.ps1','limited_interactive_runner.ps1','BoundedOperatorCapture.cs','profile-template.json','expected-routes.json','routes.json','config.json','observer-plan.json','ready.json','lease.json'|ForEach-Object{Join-Path $root $_})
foreach($case in @('valid','missingInputCapture','missingRootCapture','duplicate','writeDAC','ancestorReplace','wrongRoot','noActualProof')){
 $protected=@($required|ForEach-Object{[pscustomobject]@{path=$_;directory=($_-eq$root-or$_-eq$inputDir);granted=0}})
 if($case-eq'missingInputCapture'){$protected=@($protected|Where-Object{$_.path-ine(Join-Path $inputDir 'BoundedOperatorCapture.cs')})}
 if($case-eq'missingRootCapture'){$protected=@($protected|Where-Object{$_.path-ine(Join-Path $root 'BoundedOperatorCapture.cs')})}
 if($case-eq'duplicate'){$protected+=@($protected[0])}
 if($case-eq'writeDAC'){$protected[0].granted=0x40000}
 $access=[pscustomobject]@{schema=1;actual_limited_accesscheck=($case-ne'noActualProof');root=$(if($case-eq'wrongRoot'){'C:\foreign'}else{$root});input=$inputDir;output=$output;protected=$protected;ancestors=@([pscustomobject]@{granted=$(if($case-eq'ancestorReplace'){0x40}else{0})})}
 $proof=[pscustomobject]@{fixture_access=$access};$failed=$false
 try{. $validate}catch{$failed=$true}
 if(($case-eq'valid')-eq$failed){throw ('actual proof validator outcome differs '+$case)}
}
Write-Output 'PASS actual controller access-proof block 8 cases'
