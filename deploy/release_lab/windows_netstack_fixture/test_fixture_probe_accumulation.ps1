$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$source=Join-Path $PSScriptRoot 'product_observer.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'observer AST invalid'}

$name='Invoke-FixtureProbe';$fn=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true));if($fn.Count-ne1){throw 'actual source function absent'};. ([scriptblock]::Create($fn[0].Extent.Text))
$root='C:\owned-inert';$plan=[pscustomobject]@{nonce='unit-nonce'};$script:probeResults=@();$script:writes=@()
function Write-NewJson($p,$v){$script:writes+=@([pscustomobject]@{path=$p;value=$v})}
$bad=Invoke-FixtureProbe 'route-set' {throw 'synthetic rejected rows'}
$good=Invoke-FixtureProbe 'http-nonce' {return 'unit-value'}
if($bad.passed-ne$false-or$good.passed-ne$true-or$good.value-cne'unit-value'-or$script:probeResults.Count-ne2-or$script:writes.Count-ne2){throw 'failure short circuited independent probe'}
if(@($script:probeResults|Where-Object{-not$_.passed}).Count-ne1){throw 'failed probe disappeared'}
foreach($w in $script:writes){if($w.value.nonce-cne$plan.nonce-or$w.value.runtime_pass-ne$false){throw 'diagnostic receipt overclaims'}}
$text=[IO.File]::ReadAllText($source)
if($text-notmatch '\[Net.Sockets.SocketTaskExtensions\]::ConnectAsync'-or$text-match '\$socket\.ConnectAsync|\$socket\.Send\('){throw 'HTTP retains broken instance/partial API'}
$extension=@([Net.Sockets.SocketTaskExtensions].GetMethods()|Where-Object{$_.Name-eq'ConnectAsync'-and$_.ReturnType-eq[Threading.Tasks.Task]-and$_.GetParameters().Count-eq3-and$_.GetParameters()[1].ParameterType-eq[Net.IPAddress]})
if($extension.Count-ne1){throw 'PS5 exact static Task extension absent'}
foreach($name in @('route-set','route-feed-http','http-nonce','dns-reorder-invariance')){if($text-notlike('*Invoke-FixtureProbe '+"'"+$name+"'"+'*')){throw 'canonical probe scope missing'}}
if($text-match 'TunnelPinnedTls|Resolve-DnsName|OwnedPinnedTlsValidator'){throw 'out-of-scope TLS/resolver copied'}
'PASS actual independent probe error/success + diagnostic bounds + PS5 static method + canonical scope (5)'
