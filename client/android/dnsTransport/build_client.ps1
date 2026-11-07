param(
    [ValidateSet('arm64-v8a','armeabi-v7a','x86_64','x86')][string]$Abi = 'arm64-v8a',
    [Parameter(Mandatory=$true)][string]$GoExecutable,
    [Parameter(Mandatory=$true)][string]$NdkDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$sourceCommit = '0c5c52a57d899c05428c116898941761a2ed83c2'
$module = 'www.bamsoftware.com/git/dnstt.git'
$moduleSum = 'h1:8i4tQWwBCrhsn6+c8fpjSIyaa+u0MOvdOa1FIxNOz6M='
$architectures = @{
    'arm64-v8a' = @('arm64','aarch64-none-linux-android28')
    'armeabi-v7a' = @('arm','armv7a-linux-androideabi28')
    'x86_64' = @('amd64','x86_64-none-linux-android28')
    'x86' = @('386','i686-none-linux-android28')
}
$platform = if ($IsLinux) { 'linux-x86_64' } elseif ($IsMacOS) { 'darwin-x86_64' } else { 'windows-x86_64' }
$suffix = if ($platform -eq 'windows-x86_64') { '.exe' } else { '' }
$compiler = Join-Path $NdkDirectory "toolchains/llvm/prebuilt/$platform/bin/clang$suffix"
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Android NDK clang not found' }
$goTool = (Resolve-Path -LiteralPath $GoExecutable).Path
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$binary = Join-Path $outputRoot 'libdnstt.so'
$variableNames = @('GOMAXPROCS','GOTOOLCHAIN','GOOS','GOARCH','GOARM','CGO_ENABLED','CC')
$saved = @{}
foreach ($name in $variableNames) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:GOMAXPROCS = '2'; $env:GOTOOLCHAIN = 'local'
    $env:GOOS = 'android'; $env:GOARCH = $architectures[$Abi][0]; $env:CGO_ENABLED = '1'
    if ($Abi -eq 'armeabi-v7a') { $env:GOARM = '7' }
    $env:CC = '"' + $compiler.Replace('\','/') + '" --target=' + $architectures[$Abi][1]
    $json = & $goTool mod download -json "$module@$sourceCommit"
    if ($LASTEXITCODE -ne 0) { throw 'Pinned DNSTT source download failed' }
    $source = ($json -join "`n") | ConvertFrom-Json
    if ($source.Sum -ne $moduleSum -or $source.Version -ne 'v1.20260501.0') { throw 'DNSTT source identity mismatch' }
    Push-Location $source.Dir
    try {
        & $goTool build -p 2 -trimpath -buildmode=pie -ldflags='-s -w -extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384' -o $binary ./dnstt-client
        if ($LASTEXITCODE -ne 0) { throw 'Android DNSTT component build failed' }
    } finally { Pop-Location }
    $readElf = Join-Path $NdkDirectory "toolchains/llvm/prebuilt/$platform/bin/llvm-readelf$suffix"
    $segments = @(& $readElf -lW $binary | Where-Object { $_ -match '^\s*LOAD\s' })
    if ($LASTEXITCODE -ne 0 -or $segments.Count -eq 0) { throw 'Cannot verify DNS component ELF segments' }
    foreach ($segment in $segments) {
        $fields = ($segment.Trim() -split '\s+')
        $alignment = [Convert]::ToInt64($fields[-1].Substring(2),16)
        $offset = [Convert]::ToInt64($fields[1].Substring(2),16)
        $address = [Convert]::ToInt64($fields[2].Substring(2),16)
        if ($alignment -lt 16384 -or ($offset % 16384) -ne ($address % 16384)) {
            throw 'DNS component is not compatible with Android 16 KiB pages'
        }
    }
    $manifest = [ordered]@{
        schema = 1; abi = $Abi; minimumApi = 28; sourceCommit = $sourceCommit
        sourceVersion = $source.Version; sourceModuleSum = $moduleSum
        minimumPageAlignment = 16384
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'dnstt-manifest.json') -Encoding utf8
    Write-Output "Prepared native DNS transport component for $Abi; no Amnezia application or APK built."
} finally {
    foreach ($name in $variableNames) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
