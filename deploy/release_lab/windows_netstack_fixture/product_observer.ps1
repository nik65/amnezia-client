[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PlanPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
# Executed only by the fixed adapter's owned interactive guest task.
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-NewJson([string]$p,$v){$bytes=[Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 20 -Compress));$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length)}finally{$f.Dispose()}}
function Quote([string]$s){'"'+[regex]::Replace(([regex]::Replace($s,'(\\*)"','$1$1\"')),'(\\+)$','$1$1')+'"'}
function Identity($p){[ordered]@{pid=[int]$p.Id;start_ticks=$p.StartTime.ToUniversalTime().Ticks;exe=[string]$p.Path}}
function Same($a,$b){($a|ConvertTo-Json -Compress)-ceq($b|ConvertTo-Json -Compress)}
function Status([string]$app){return RequestLimited 'status'}
function Native {
 $p=New-Object IO.Pipes.NamedPipeClientStream('.', 'ProtectedPrefix\Administrators\AmneziaWG\AmneziaVPN',[IO.Pipes.PipeDirection]::InOut)
 try{$p.Connect(2000);$request=[Text.Encoding]::ASCII.GetBytes("get=1`n`n");$p.Write($request,0,$request.Length);$p.Flush();$raw=New-Object IO.MemoryStream;$buf=New-Object byte[] 4096
  while($raw.Length-lt 65536){$read=$p.ReadAsync($buf,0,$buf.Length);if(-not $read.Wait(2000)){throw 'native read timeout'};$n=$read.Result;if($n-eq 0){break};$raw.Write($buf,0,$n);$text=[Text.Encoding]::UTF8.GetString($raw.ToArray());if($text.EndsWith("`n`n")){break}}
  if(-not $text.EndsWith("`n`n")){throw 'incomplete native observation'}
  $out=@{};foreach($line in ($text-split "`n")){if($line-match '^(last_handshake_time_sec|rx_bytes|tx_bytes|random_trailers|disable_cookies)=(.*)$'){$out[$matches[1]]=$matches[2]}}
  if([long]$out.last_handshake_time_sec-le 0 -or [long]$out.rx_bytes-le 0 -or [long]$out.tx_bytes-le 0){throw 'native encrypted traffic absent'}
  $script:lastNativeRaw=$text
  $out['uapi_sha256']=([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($text))|ForEach-Object{$_.ToString('x2')})-join '';return $out
 }finally{$p.Dispose()}
}
# Diagnostic probes only: monotonic 10s total including connect/auth/write/read.
function Wait-FixtureIo($task,$clock,[string]$stage){
 $remaining=10000-[int64]$clock.ElapsedMilliseconds
 if($remaining-le0){throw "$stage global deadline"}
 if(-not$task.Wait([int][Math]::Min(5000,$remaining))){throw "$stage bounded IO timeout"}
 if($clock.ElapsedMilliseconds-ge10000){throw "$stage global deadline"}
}
function Write-FixtureBytes($stream,[byte[]]$bytes,$clock){
 # Stream.WriteAsync promises all bytes or an exception, unlike Socket.Send.
 Wait-FixtureIo ($stream.WriteAsync($bytes,0,$bytes.Length)) $clock 'write'
}
function Read-FixtureBytes($stream,$clock,[int]$cap){
 $memory=New-Object IO.MemoryStream;$buffer=New-Object byte[] 4096
 try{while($true){$task=$stream.ReadAsync($buffer,0,$buffer.Length);Wait-FixtureIo $task $clock 'read';$n=$task.Result;if($n-eq0){break};$memory.Write($buffer,0,$n);if($memory.Length-gt$cap){throw 'fixture response size exceeds cap'}};return ,$memory.ToArray()}finally{$memory.Dispose()}
}

function TunnelHttp([string]$ip,[string]$hostIp,[int]$port,[string]$path,[string]$nonce){
 $socket=New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
 $stream=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
 try{$socket.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($ip),0)));Wait-FixtureIo ([Net.Sockets.SocketTaskExtensions]::ConnectAsync($socket,[Net.IPAddress]::Parse($hostIp),$port)) $clock 'HTTP connect'
  $r=[Text.Encoding]::ASCII.GetBytes("GET $path HTTP/1.1`r`nHost: $hostIp`r`nConnection: close`r`nX-Amnezia-Lab-Nonce: $nonce`r`n`r`n")
  $stream=New-Object Net.Sockets.NetworkStream($socket,$false);Write-FixtureBytes $stream $r $clock
  $all=Read-FixtureBytes $stream $clock 4194304;$text=[Text.Encoding]::ASCII.GetString($all);$split=$text.IndexOf("`r`n`r`n");if($split-lt 0 -or -not $text.StartsWith('HTTP/1.1 200 ')){throw 'fixture HTTP failed'}
  if($text.Substring(0,$split)-match '(?i)Transfer-Encoding:'){throw 'chunked evidence unsupported'}
  $body=New-Object byte[] ($all.Length-$split-4);[Array]::Copy($all,$split+4,$body,0,$body.Length);return ,$body
 }finally{if($null-ne$stream){$stream.Dispose()};$socket.Dispose();$clock.Stop()}
}

# Strict expected prefixes plus exact Windows Local on-link broadcast companions.
function Test-FixtureRouteRows($rows,[string[]]$expected,[int]$index,[string]$client){
 $prefixes=@($rows|Select-Object -ExpandProperty DestinationPrefix|Sort-Object -Unique)
 $missing=@($expected|Where-Object{$_-notin$prefixes});$broadcasts=@()
 foreach($prefix in $expected){
  if($prefix-notin$prefixes){continue};$parts=$prefix.Split('/');$bits=[int]$parts[1]
  if($bits-lt0-or$bits-gt32){throw 'expected prefix length invalid'};if($bits-ge31){continue}
  $b=[Net.IPAddress]::Parse($parts[0]).GetAddressBytes();if($b.Length-ne4){throw 'expected prefix not IPv4'}
  $ip=[uint32](([uint64]$b[0]-shl24)-bor([uint64]$b[1]-shl16)-bor([uint64]$b[2]-shl8)-bor[uint64]$b[3]);$hostMask=[uint32]([Math]::Pow(2,32-$bits)-1);$n=[uint32]($ip-bor$hostMask)
  $octets=@([int](($n-shr24)-band255),[int](($n-shr16)-band255),[int](($n-shr8)-band255),[int]($n-band255))
  $broadcasts+=@(($octets-join'.')+'/32')
 }
 $automatic=@("$client/32",'224.0.0.0/4','255.255.255.255/32');$unexpected=@();$companions=@()
 foreach($row in $rows){
  if([int]$row.InterfaceIndex-ne$index){$unexpected+=@($row);continue}
  if($row.DestinationPrefix-in$expected){continue}
  if($row.DestinationPrefix-in$broadcasts){if($row.NextHop-ceq'0.0.0.0'-and[string]$row.Protocol-ceq'Local'){$companions+=@($row)}else{$unexpected+=@($row)};continue}
  if($row.DestinationPrefix-in$automatic){continue}
  $unexpected+=@($row)
 }
 return [ordered]@{passed=($missing.Count-eq0-and$unexpected.Count-eq0);missing=$missing;unexpected=$unexpected;derivedBroadcasts=@($broadcasts|Sort-Object -Unique);acceptedCompanions=$companions}
}
function Invoke-FixtureProbe([string]$name,[scriptblock]$action){
 try{$value=&$action;$record=[ordered]@{name=$name;passed=$true;value=$value}}catch{$record=[ordered]@{name=$name;passed=$false;error_type=$_.Exception.GetType().FullName;error=$_.Exception.Message;script_stack=$_.ScriptStackTrace}}
 $script:probeResults+=@($record);Write-NewJson (Join-Path $root ('observer-probe-'+$name+'.json')) ([ordered]@{nonce=$plan.nonce;probe=$record;runtime_pass=$false});return $record
}


$script:limited=$null
$plan=$null;$gui=$null;$initial=$null;$failure=$null
try{
 $root=Split-Path -Parent $PlanPath;$plan=Get-Content -LiteralPath $PlanPath -Raw|ConvertFrom-Json
 if([Diagnostics.Process]::GetCurrentProcess().SessionId-le 0 -or [Security.Principal.WindowsIdentity]::GetCurrent().Name-notmatch '\\labadmin$'){throw 'interactive owned account required'}
 $marker=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $root) 'run-marker.txt')
 if($marker-notcontains "amnezia-release-lab:$($plan.run_id):windows-x64" -or $marker-notcontains "case_id=$($plan.case_id)" -or $marker-notcontains "vm_id=$($plan.vm_id)"){throw 'observer marker mismatch'}
 $app='C:\Program Files\AmneziaVPN\AmneziaVPN.exe';if((Hash $app)-cne $plan.installed_exe_sha256){throw 'installed product bytes differ'}
 if(@(Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue).Count-ne 0){throw 'fresh guest GUI required'}
 foreach($f in @('profile-template.json','expected-routes.json','routes.json')){if((Hash (Join-Path $root $f))-cne $plan.files.$f){throw 'staged observer bytes changed'}}
 foreach($f in @('limited_interactive_controller.ps1','limited_interactive_runner.ps1','BoundedOperatorCapture.cs')){
  $source=Join-Path $root $f;$item=Get-Item -LiteralPath $source -Force
  if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or$item.Length-gt131072-or(Hash $source)-cne$plan.files.$f){throw 'staged limited source changed'}
 }
 . (Join-Path $root 'limited_interactive_controller.ps1')
 $ready=Get-Content -LiteralPath (Join-Path $root 'ready.json') -Raw|ConvertFrom-Json
 if($ready.run_id-cne $plan.run_id -or $ready.case_id-cne $plan.case_id -or $ready.vm_id-cne $plan.vm_id -or $ready.nonce-cne $plan.nonce){throw 'helper ready binding mismatch'}
 $profile=Get-Content -LiteralPath (Join-Path $root 'profile-template.json') -Raw|ConvertFrom-Json
 if($profile.defaultContainer-cne 'amnezia-awg2' -or @($profile.containers).Count-ne 1){throw 'unsupported fixture profile'}
 $last=$profile.containers[0].awg.last_config|ConvertFrom-Json
 # Only the reviewed fixture endpoint changes. Never seed persisted settings/journal.
 $last.hostName='127.0.0.1';$last.port=[int]$ready.source_udp_port
 $last.config=[regex]::Replace($last.config,'(?m)^Endpoint = [^\r\n]+$',"Endpoint = 127.0.0.1:$($ready.source_udp_port)")
 $profile.hostName='127.0.0.1';$profile.containers[0].awg.port=[string]$ready.source_udp_port;$profile.containers[0].awg.last_config=($last|ConvertTo-Json -Depth 16 -Compress)
 $args='--import '+(Quote ($profile|ConvertTo-Json -Depth 20 -Compress))+' --connect 0'
 $gui=StartLimitedGui $root $plan $args
 $initial=Identity $gui;$deadline=[DateTime]::UtcNow.AddSeconds(75)
 do{Start-Sleep -Milliseconds 500;try{$status=Status $app;$native=Native;break}catch{if($gui.HasExited){throw 'owned GUI exited'};if([DateTime]::UtcNow-gt $deadline){throw 'product connect timeout'}}}while($true)
 $adapter=@(Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.IPAddress-ceq $plan.client_address});if($adapter.Count-ne 1){throw 'ambiguous product tunnel interface'};$index=[int]$adapter[0].InterfaceIndex
 $expectedJson=Get-Content -LiteralPath (Join-Path $root 'expected-routes.json') -Raw|ConvertFrom-Json
 $expected=@($expectedJson|Sort-Object -Unique)
 if($expected.Count-lt 1 -or $expected.Count-ne $plan.fixture_prefix_count -or $plan.route_shape-cne 'synthetic-windows-dataplane-v1'){throw 'synthetic fixture shape mismatch'}
 $script:probeResults=@()
 $routeRows=@(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4|Select-Object DestinationPrefix,NextHop,InterfaceIndex,Protocol,PolicyStore,Publish,ValidLifetime,PreferredLifetime)
 $actual=@($routeRows|Select-Object -ExpandProperty DestinationPrefix|Sort-Object -Unique)
 # Exact raw UAPI stays in this bounded private guest capture, never printed.
 Write-NewJson (Join-Path $root 'observer-native-before.json') ([ordered]@{nonce=$plan.nonce;utc=[DateTime]::UtcNow.ToString('o');filtered=$native;raw_uapi=$script:lastNativeRaw;checkpoint_only=$true;runtime_pass=$false})
 $routeAssessment=Test-FixtureRouteRows $routeRows $expected $index $plan.client_address
 Write-NewJson (Join-Path $root 'observer-routes.json') ([ordered]@{nonce=$plan.nonce;expected=$expected;actual=$actual;fullRows=$routeRows;assessment=$routeAssessment;interfaceIndex=$index;checkpoint_only=$true;runtime_pass=$false})
 $routeProof=Invoke-FixtureProbe 'route-set' {if(-not$routeAssessment.passed){throw 'native managed route set differs'};return $routeAssessment}
 $service=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'";$tunnel=Get-CimInstance Win32_Service -Filter "Name='AmneziaWGTunnel`$AmneziaVPN'"
 $stableBefore=@($routeRows|Sort-Object DestinationPrefix,NextHop,InterfaceIndex,Protocol|Select-Object DestinationPrefix,NextHop,InterfaceIndex,Protocol)
 $baseline=[ordered]@{gui=$initial;service=(Identity (Get-Process -Id $service.ProcessId));tunnel=(Identity (Get-Process -Id $tunnel.ProcessId));routes=$actual}
 $feedProof=Invoke-FixtureProbe 'route-feed-http' {
  $body=TunnelHttp $plan.client_address '172.29.172.253' 17864 '/rules.json' $plan.nonce
  $hash=([Security.Cryptography.SHA256]::Create().ComputeHash($body)|ForEach-Object{$_.ToString('x2')})-join''
  if($hash-cne$plan.files.'routes.json'){throw 'encrypted route feed bytes mismatch'};return $hash
 }
 $httpProof=Invoke-FixtureProbe 'http-nonce' {$probe=TunnelHttp $plan.client_address '172.29.172.251' 18082 '/probe' $plan.nonce;if([Text.Encoding]::ASCII.GetString($probe)-cne$plan.nonce){throw 'encrypted probe nonce mismatch'};return $true}
 $reorderProof=Invoke-FixtureProbe 'dns-reorder-invariance' {
  $dns=@((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses)
  if($dns.Count-ne2-or$dns[0]-eq$dns[1]){throw 'two fixture DNS addresses required for reorder'}
  try{Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @($dns[1],$dns[0]);Start-Sleep -Seconds 15
   $rowsAfter=@(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4|Select-Object DestinationPrefix,NextHop,InterfaceIndex,Protocol,PolicyStore,Publish,ValidLifetime,PreferredLifetime)
   $after=[ordered]@{gui=(Identity (Get-Process -Id $gui.Id));service=(Identity (Get-Process -Id $service.ProcessId));tunnel=(Identity (Get-Process -Id $tunnel.ProcessId));routes=@($rowsAfter|Select-Object -ExpandProperty DestinationPrefix|Sort-Object -Unique)}
   $statusAfter=Status $app;$nativeAfter=Native
   Write-NewJson (Join-Path $root 'observer-native-after.json') ([ordered]@{nonce=$plan.nonce;utc=[DateTime]::UtcNow.ToString('o');filtered=$nativeAfter;raw_uapi=$script:lastNativeRaw;full_route_rows=$rowsAfter;status=$statusAfter;checkpoint_only=$true;runtime_pass=$false})
   $assessmentAfter=Test-FixtureRouteRows $rowsAfter $expected $index $plan.client_address
   $stableAfter=@($rowsAfter|Sort-Object DestinationPrefix,NextHop,InterfaceIndex,Protocol|Select-Object DestinationPrefix,NextHop,InterfaceIndex,Protocol)
   if(-not$assessmentAfter.passed-or-not(Same $stableBefore $stableAfter)){throw 'stable route fields changed after DNS reorder'}
   if(-not(Same $baseline $after)){throw 'route/PID identity changed after DNS reorder'}
   if([long]$nativeAfter.rx_bytes-lt[long]$native.rx_bytes-or[long]$nativeAfter.tx_bytes-lt[long]$native.tx_bytes){throw 'native traffic counter reset'}
   return [ordered]@{after=$after;native=$nativeAfter}
  }finally{Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dns}
 }
 Write-NewJson (Join-Path $root 'observer-probes.json') ([ordered]@{nonce=$plan.nonce;probes=$script:probeResults;allPassed=(@($script:probeResults|Where-Object{-not$_.passed}).Count-eq0);runtime_pass=$false})
 if(@($script:probeResults|Where-Object{-not$_.passed}).Count-ne0){throw 'one or more independent fixture probes failed'}
 $bodySHA=$feedProof.value;$after=$reorderProof.value.after;$nativeAfter=$reorderProof.value.native
 $gui.Refresh();if($gui.MainWindowHandle-eq 0){throw 'real mapped GUI absent'}
 Write-NewJson (Join-Path $root 'observer.json') ([ordered]@{schema=1;run_id=$plan.run_id;case_id=$plan.case_id;vm_id=$plan.vm_id;nonce=$plan.nonce;task_token=$plan.task_token;origin='guest';injected=$false;route_shape=$plan.route_shape;logged_production_shape=1263;fixture_prefix_count=$expected.Count;feed_sha256=$bodySHA;known_nonce_proved=$true;limited_gui_operator=$true;limited_started_proof_sha256=(Hash (Join-Path $script:limited.output 'started.json'));before=$baseline;after=$after;native_before=$native;native_after=$nativeAfter;gui_visible=$true;production_journal=$false;migration_pass=$false;runtime_pass=$false;capability_observed=$true;limitation='PID_route_polling_does_not_prove_worker_epoch_or_every_disconnect_event'})
}catch{$failure=$true;if($null-ne $plan){try{Write-NewJson (Join-Path $root 'observer-failure.json') @{failed=$true;run_id=$plan.run_id;case_id=$plan.case_id;task_token=$plan.task_token}}catch{}}}
finally{if(Get-Command CloseLimited -ErrorAction SilentlyContinue){try{CloseLimited}catch{$failure=$true}}}
if($failure){exit 1}
