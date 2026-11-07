$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$source=Join-Path $PSScriptRoot 'product_observer.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'observer AST invalid'}
foreach($name in @('Test-FixtureRouteRows')){$fn=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true));if($fn.Count-ne1){throw 'actual source function ambiguous'};. ([scriptblock]::Create($fn[0].Extent.Text))}
function Row($prefix,$protocol='NetMgmt',$hop='0.0.0.0',$index=7){[pscustomobject]@{DestinationPrefix=$prefix;Protocol=$protocol;NextHop=$hop;InterfaceIndex=$index}}
$expected=@('172.29.172.251/32','172.29.172.252/32','172.29.172.253/32','198.18.0.0/24','198.19.255.128/25')
$base=@($expected|ForEach-Object{Row $_});$results=@()
function Check($name,$rows,$prefixes,$pass){$r=Test-FixtureRouteRows $rows $prefixes 7 '10.244.31.2';if($r.passed-ne$pass){throw "case $name differs"};$script:results+=@([ordered]@{case=$name;passed=$true;expectedAcceptance=$pass;derived=$r.derivedBroadcasts})}
Check 'required-only' $base $expected $true
Check 'exact-local-broadcasts' ($base+@(Row '198.18.0.255/32' 'Local';Row '198.19.255.255/32' 'Local')) $expected $true
Check 'missing-required' @($base|Where-Object DestinationPrefix -ne '172.29.172.252/32') $expected $false
Check 'unrelated-host' ($base+@(Row '198.18.0.254/32' 'Local')) $expected $false
Check 'wrong-protocol' ($base+@(Row '198.18.0.255/32' 'NetMgmt')) $expected $false
Check 'wrong-gateway' ($base+@(Row '198.18.0.255/32' 'Local' '1.2.3.4')) $expected $false
Check 'wrong-interface' ($base+@(Row '198.18.0.255/32' 'Local' '0.0.0.0' 8)) $expected $false
Check 'explicit-broadcast-host-required' @((Row '198.18.0.0/24');(Row '198.18.0.255/32')) @('198.18.0.0/24','198.18.0.255/32') $true
Check 'explicit-broadcast-host-missing' @((Row '198.18.0.0/24')) @('198.18.0.0/24','198.18.0.255/32') $false
Check 'slash31-no-derived' @((Row '198.18.0.0/31');(Row '198.18.0.1/32' 'Local')) @('198.18.0.0/31') $false
Check 'slash32-no-derived' @((Row '198.18.0.1/32');(Row '198.18.0.255/32' 'Local')) @('198.18.0.1/32') $false
Check 'absent-parent-does-not-authorize' @((Row '198.18.0.255/32' 'Local')) @('198.18.0.0/24') $false
Check 'slash0-boundary' @((Row '0.0.0.0/0');(Row '255.255.255.255/32' 'Local')) @('0.0.0.0/0') $true
Check 'slash0-wrong-protocol-rejected' @((Row '0.0.0.0/0');(Row '255.255.255.255/32' 'NetMgmt')) @('0.0.0.0/0') $false
Check 'slash30-boundary' @((Row '198.18.0.4/30');(Row '198.18.0.7/32' 'Local')) @('198.18.0.4/30') $true
"$($results.Count) route cases PASS"
