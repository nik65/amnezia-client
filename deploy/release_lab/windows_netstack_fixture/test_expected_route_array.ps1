param([string]$ObserverPath=(Join-Path $PSScriptRoot 'product_observer.ps1'))
$ErrorActionPreference='Stop'
$text=[IO.File]::ReadAllText($ObserverPath)
$lines=@($text -split '\r?\n'|Where-Object{$_ -match '^ \$expected(Json)?='})
if($lines.Count-ne2-or$lines[0]-notmatch 'ConvertFrom-Json$'-or$lines[1]-cne' $expected=@($expectedJson|Sort-Object -Unique)'){throw 'actual observer array expression differs'}
$new=[ScriptBlock]::Create(($lines-join"`n")+"`n"+'[pscustomobject]@{count=$expected.Count;values=$expected}')
$old=[ScriptBlock]::Create(' $expected=@(Get-Content -LiteralPath (Join-Path $root ''expected-routes.json'') -Raw|ConvertFrom-Json|Sort-Object -Unique)' + "`n" + '[pscustomobject]@{count=$expected.Count;values=$expected}')
$root=Join-Path ([IO.Path]::GetTempPath()) ('owned-route-array-'+[Guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $root|Out-Null
try{
 $cases=@(@{json='["a","b","c","d","e"]';count=5},@{json='["a"]';count=1},@{json='["b","a","a"]';count=2},@{json='[]';count=0})
 $checks=0
 foreach($case in $cases){[IO.File]::WriteAllText((Join-Path $root 'expected-routes.json'),$case.json);$result=&$new;if($result.count-ne$case.count){throw 'actual decoded-array source count differs'};$checks++}
 [IO.File]::WriteAllText((Join-Path $root 'expected-routes.json'),$cases[0].json);$red=&$old
 if($PSVersionTable.PSVersion.Major-eq5-and$red.count-ne1){throw 'PS5 old expression RED not reproduced'}
 [ordered]@{passed=$true;actualPowerShell=$PSVersionTable.PSVersion.ToString();actualSourceCases=$checks;oldCount=$red.count;newManyCount=5;sourceSha256=(Get-FileHash $ObserverPath -Algorithm SHA256).Hash.ToLower();guestStarted=$false;productExecuted=$false}|ConvertTo-Json -Compress
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
