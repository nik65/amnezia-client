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
function Status([string]$app){$raw=& $app --status --json 2>$null|Out-String;if($LASTEXITCODE-ne 0){throw 'operator status unavailable'};$v=$raw|ConvertFrom-Json;if($v.PSObject.Properties.Name -contains 'result'){$v=$v.result};if($v.connected-ne $true -or $v.stateFresh-ne $true){throw 'product not freshly connected'};return $v}
function Native {
 $p=New-Object IO.Pipes.NamedPipeClientStream('.', 'ProtectedPrefix\Administrators\AmneziaWG\AmneziaVPN',[IO.Pipes.PipeDirection]::InOut)
 try{$p.Connect(2000);$request=[Text.Encoding]::ASCII.GetBytes("get=1`n`n");$p.Write($request,0,$request.Length);$p.Flush();$raw=New-Object IO.MemoryStream;$buf=New-Object byte[] 4096
  while($raw.Length-lt 65536){$read=$p.ReadAsync($buf,0,$buf.Length);if(-not $read.Wait(2000)){throw 'native read timeout'};$n=$read.Result;if($n-eq 0){break};$raw.Write($buf,0,$n);$text=[Text.Encoding]::UTF8.GetString($raw.ToArray());if($text.EndsWith("`n`n")){break}}
  if(-not $text.EndsWith("`n`n")){throw 'incomplete native observation'}
  $out=@{};foreach($line in ($text-split "`n")){if($line-match '^(last_handshake_time_sec|rx_bytes|tx_bytes|random_trailers|disable_cookies)=(.*)$'){$out[$matches[1]]=$matches[2]}}
  if([long]$out.last_handshake_time_sec-le 0 -or [long]$out.rx_bytes-le 0 -or [long]$out.tx_bytes-le 0){throw 'native encrypted traffic absent'}
  $out['uapi_sha256']=([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($text))|ForEach-Object{$_.ToString('x2')})-join '';return $out
 }finally{$p.Dispose()}
}
function TunnelHttp([string]$ip,[string]$hostIp,[int]$port,[string]$path,[string]$nonce){
 $socket=New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
 try{$socket.SendTimeout=5000;$socket.ReceiveTimeout=5000;$socket.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($ip),0)));$connect=$socket.ConnectAsync($hostIp,$port);if(-not $connect.Wait(5000)){throw 'HTTP connect timeout'}
  $r=[Text.Encoding]::ASCII.GetBytes("GET $path HTTP/1.1`r`nHost: $hostIp`r`nConnection: close`r`nX-Amnezia-Lab-Nonce: $nonce`r`n`r`n");[void]$socket.Send($r)
  $stream=New-Object Net.Sockets.NetworkStream($socket,$false);$memory=New-Object IO.MemoryStream;$buffer=New-Object byte[] 4096
  while(($n=$stream.Read($buffer,0,$buffer.Length))-gt 0){$memory.Write($buffer,0,$n);if($memory.Length-gt 4194304){throw 'HTTP evidence too large'}}
  $all=$memory.ToArray();$text=[Text.Encoding]::ASCII.GetString($all);$split=$text.IndexOf("`r`n`r`n");if($split-lt 0 -or -not $text.StartsWith('HTTP/1.1 200 ')){throw 'fixture HTTP failed'}
  if($text.Substring(0,$split)-match '(?i)Transfer-Encoding:'){throw 'chunked evidence unsupported'}
  $body=New-Object byte[] ($all.Length-$split-4);[Array]::Copy($all,$split+4,$body,0,$body.Length);return ,$body
 }finally{$socket.Dispose()}
}
$plan=$null;$gui=$null;$initial=$null;$failure=$null
try{
 $root=Split-Path -Parent $PlanPath;$plan=Get-Content -LiteralPath $PlanPath -Raw|ConvertFrom-Json
 if([Diagnostics.Process]::GetCurrentProcess().SessionId-le 0 -or [Security.Principal.WindowsIdentity]::GetCurrent().Name-notmatch '\\labadmin$'){throw 'interactive owned account required'}
 $marker=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $root) 'run-marker.txt')
 if($marker-notcontains "amnezia-release-lab:$($plan.run_id):windows-x64" -or $marker-notcontains "case_id=$($plan.case_id)" -or $marker-notcontains "vm_id=$($plan.vm_id)"){throw 'observer marker mismatch'}
 $app='C:\Program Files\AmneziaVPN\AmneziaVPN.exe';if((Hash $app)-cne $plan.installed_exe_sha256){throw 'installed product bytes differ'}
 if(@(Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue).Count-ne 0){throw 'fresh guest GUI required'}
 foreach($f in @('profile-template.json','expected-routes.json','routes.json')){if((Hash (Join-Path $root $f))-cne $plan.files.$f){throw 'staged observer bytes changed'}}
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
 $gui=Start-Process -FilePath $app -ArgumentList $args -PassThru -WindowStyle Normal
 $initial=Identity $gui;$deadline=[DateTime]::UtcNow.AddSeconds(75)
 do{Start-Sleep -Milliseconds 500;try{$status=Status $app;$native=Native;break}catch{if($gui.HasExited){throw 'owned GUI exited'};if([DateTime]::UtcNow-gt $deadline){throw 'product connect timeout'}}}while($true)
 $adapter=@(Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.IPAddress-ceq $plan.client_address});if($adapter.Count-ne 1){throw 'ambiguous product tunnel interface'};$index=[int]$adapter[0].InterfaceIndex
 $expected=@(Get-Content -LiteralPath (Join-Path $root 'expected-routes.json') -Raw|ConvertFrom-Json|Sort-Object -Unique)
 if($expected.Count-lt 1 -or $expected.Count-ne $plan.fixture_prefix_count -or $plan.route_shape-cne 'synthetic-windows-dataplane-v1'){throw 'synthetic fixture shape mismatch'}
 $actual=@(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4|Select-Object -ExpandProperty DestinationPrefix|Sort-Object -Unique)
 $automatic=@("$($plan.client_address)/32",'224.0.0.0/4','255.255.255.255/32')
 $managed=@($actual|Where-Object{$_-notin $automatic -or $_-in $expected})
 if(@(Compare-Object $expected $managed).Count-ne 0){throw 'native managed route set differs'}
 $service=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'";$tunnel=Get-CimInstance Win32_Service -Filter "Name='AmneziaWGTunnel`$AmneziaVPN'"
 $baseline=[ordered]@{gui=$initial;service=(Identity (Get-Process -Id $service.ProcessId));tunnel=(Identity (Get-Process -Id $tunnel.ProcessId));routes=$actual}
 $body=TunnelHttp $plan.client_address '172.29.172.253' 17864 '/rules.json' $plan.nonce
 $bodySHA=([Security.Cryptography.SHA256]::Create().ComputeHash($body)|ForEach-Object{$_.ToString('x2')})-join '';if($bodySHA-cne $plan.files.'routes.json'){throw 'encrypted route feed bytes mismatch'}
 $probe=TunnelHttp $plan.client_address '172.29.172.251' 18082 '/probe' $plan.nonce;if([Text.Encoding]::ASCII.GetString($probe)-cne $plan.nonce){throw 'encrypted probe nonce mismatch'}
 $dns=@((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses)
 if($dns.Count-ne 2 -or $dns[0]-eq $dns[1]){throw 'two fixture DNS addresses required for reorder'}
 try{Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @($dns[1],$dns[0]);Start-Sleep -Seconds 15
  $after=[ordered]@{gui=(Identity (Get-Process -Id $gui.Id));service=(Identity (Get-Process -Id $service.ProcessId));tunnel=(Identity (Get-Process -Id $tunnel.ProcessId));routes=@(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4|Select-Object -ExpandProperty DestinationPrefix|Sort-Object -Unique)}
  if(-not(Same $baseline $after)){throw 'route/PID identity changed after DNS reorder'}
  $statusAfter=Status $app;$nativeAfter=Native
  if([long]$nativeAfter.rx_bytes-lt [long]$native.rx_bytes -or [long]$nativeAfter.tx_bytes-lt [long]$native.tx_bytes){throw 'native traffic counter reset'}
 }finally{Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dns}
 $gui.Refresh();if($gui.MainWindowHandle-eq 0){throw 'real mapped GUI absent'}
 Write-NewJson (Join-Path $root 'observer.json') ([ordered]@{schema=1;run_id=$plan.run_id;case_id=$plan.case_id;vm_id=$plan.vm_id;nonce=$plan.nonce;task_token=$plan.task_token;origin='guest';injected=$false;route_shape=$plan.route_shape;logged_production_shape=1263;fixture_prefix_count=$expected.Count;feed_sha256=$bodySHA;known_nonce_proved=$true;before=$baseline;after=$after;native_before=$native;native_after=$nativeAfter;gui_visible=$true;production_journal=$false;migration_pass=$false;runtime_pass=$false;capability_observed=$true;limitation='PID_route_polling_does_not_prove_worker_epoch_or_every_disconnect_event'})
}catch{$failure=$true;if($null-ne $plan){try{Write-NewJson (Join-Path $root 'observer-failure.json') @{failed=$true;run_id=$plan.run_id;case_id=$plan.case_id;task_token=$plan.task_token}}catch{}}}
finally{if($null-ne $gui){try{if(-not $gui.HasExited -and (Same $initial (Identity $gui))){$gui.CloseMainWindow()|Out-Null;if(-not $gui.WaitForExit(10000)){throw 'owned GUI graceful close pending'}}}catch{$failure=$true}}}
if($failure){exit 1}
